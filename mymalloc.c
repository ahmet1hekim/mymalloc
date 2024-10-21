//İBRAHİM EMRE ÇELENLİ 22120205061 BM2 
//AHMET  HEKİM 22120205032 BM2 


#include "mymalloc.h"
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
Block *find_block(size_t data_size, Strategy strategy);

static int first = 1; //malloc'un ilk kez çağrıldığını kontrol etmek için gerekli
//ilerde kullanılmak üzere blockların sonuna metadata ekler
void tagekle(Block *new_block){
        Tag* tag = (Tag *)((char*)new_block + sizeof(Block) + (new_block->info.size)*16);
        tag->isfree = new_block->info.isfree;
        tag->size = new_block->info.size;
}


void *mymalloc(size_t size) {

        if(size > HEAP_SIZE){
              return NULL;   
        }    
    size = (size + 15) & ~15; //size 16'nın katı olacak şekilde güncellenir 
    Block *selected_block;
    //ilk bloğun olma ve olmama durumuna göre sbrk ile heape veya heapten blocklar oluşturulup yer verilir
    if(first != 1){
        selected_block = find_block(size,strategy);
    }
    
    if (first == 1 || (selected_block == NULL)) { 
        //heapten yer verilir
        Block *new_block;
        if(first == 1){
            heap_start = sbrk(HEAP_SIZE);
            heap_end = (Block*)((char*)heap_start + HEAP_SIZE);
            new_block=heap_start;
        }
        else{
            sbrk(HEAP_SIZE);
            new_block = heap_end;
            Block *prev_of_heap_end = prev_block_in_addr(heap_end);
            if(prev_of_heap_end->info.isfree){
                new_block = prev_of_heap_end;
            }
            heap_end = (Block *)((char *)heap_end + HEAP_SIZE);
        }
        //oluşturulan blockun infoları yazılır
        new_block->next = NULL;
        new_block->prev = NULL;
        new_block->info.isfree = 0;
        new_block->info.size = numberof16blocks(size);
        tagekle(new_block);
        
        if(first == 1){
            free_list = next_block_in_addr(new_block);
            free_list->info.isfree = 1;
            free_list->info.size = numberof16blocks(((char*)heap_end - (char*)free_list - sizeof(Block) - sizeof(Tag)));
            free_list->prev = NULL;
            free_list->next = NULL; 
            last_freed = free_list;
            first = 0;
            tagekle(free_list);
            return new_block->data;
        }
        else{
            Block *returning_block = split_block(new_block, size);
            return returning_block->data; 
        }       
    }

    if (selected_block == NULL){
        return NULL;
    }

    Block *returning_block = split_block(selected_block, size);
    return returning_block->data;
}


void myfree(void *p) {
    //ordered yada unordered olmasına göre free edilen blok listelere eklenir
    if(listtype == ADDR_ORDERED_LIST){

        Block *block_to_free = (Block *)((char *)p - sizeof(Block));
        block_to_free->info.isfree = 1;
        tagekle(block_to_free);

        Block *end, *current = free_list;
        int flag = 0;
        while(current < block_to_free && current->next != NULL){
            current = current->next;
            if(current > block_to_free){
                flag = 1;
            }
        }
        
        end = current;
        if(end < block_to_free){
            block_to_free->next = NULL;
            block_to_free->prev = end;
            end->next = block_to_free;
        }
        else{
            block_to_free->next = end;            
            block_to_free->prev = end->prev;
            if(end->prev != NULL){
                end->prev->next = block_to_free;
            } 
            end->prev = block_to_free;
        }
        
        

        current = free_list;
        flag = 0;
        while (current != NULL){
            if(block_to_free < current){
                if(current->prev != NULL){
                    current->prev->next = block_to_free;
                }
                
                block_to_free->next = current;
                block_to_free->prev = current->prev;
                if(current <= free_list){
                    free_list = block_to_free;
                }
                flag = 1;
                break;
            }
                current = current->next;
        }

        if (flag == 0){
            current->next = block_to_free;
            block_to_free->next = NULL;
        }

        block_to_free = right_coalesce(block_to_free);
        block_to_free = left_coalesce(block_to_free);

        last_freed = block_to_free;

        if (free_list == NULL) {
            free_list = block_to_free;
        } 

    }

    else{

        Block *block_to_free = (Block *)((char *)p - offsetof(Block, data));
        block_to_free->info.isfree = 1;  
        block_to_free = right_coalesce(block_to_free);
        block_to_free = left_coalesce(block_to_free);
        last_freed->next = block_to_free;
        block_to_free->prev = last_freed;
        last_freed = block_to_free;
        block_to_free->next = NULL;
        
        
    }
}

Block *find_block(size_t data_size, Strategy strategy) {
    //istenilen stratejiye göre uygun blok bulunur
    Block *current;

    switch (strategy) {

        case BEST_FIT:;
            Block *best_fit = free_list;
            Block *current = free_list;
            while(current != NULL){
                if(best_fit != current && current->info.size > numberof16blocks(data_size) && current->info.size < best_fit->info.size){
                    best_fit = current;
                }
                else{
                    current = next_block_in_freelist(current);
                }
            }
            return best_fit;
            break;
          

        case NEXT_FIT:;
            Block *next_fit = last_freed;
            current = free_list;
            while(current != NULL){
                if(next_fit != current && current->info.size > numberof16blocks(data_size)){
                    next_fit = current;
                    break;
                }
                else{
                    current = next_block_in_freelist(current);
                }
            }
            return next_fit;
            break;

 

        case FIRST_FIT:;
            Block *first_fit = free_list;
            current = free_list;
            while(current != NULL){
                if(first_fit != current && current->info.size > numberof16blocks(data_size)){
                    first_fit = current;
                    break;
                }
                else{
                    current = next_block_in_freelist(current);
                }
            }
            return first_fit;
            break;


        case WORST_FIT:;
            Block *worst_fit = free_list;
            current = free_list;
            while(current != NULL){
                if(worst_fit != current && current->info.size > numberof16blocks(data_size) && current->info.size > worst_fit->info.size){
                    worst_fit = current;
                }
                else{
                    current = next_block_in_freelist(current);
                }
            }
            return worst_fit;
            break;

        }

    return NULL;
}

Block *split_block(Block *b, size_t size) {
    //gerektiğinde blok bölünür
    size_t nsize = numberof16blocks(size);

    Block *free_block = (Block *)((char *)b + sizeof(Block) + size + sizeof(Tag));

    // Oluşturulan bloğun bilgileri ayarlanıyor
    free_block->info.size = numberof16blocks(((b->info.size * 16) - sizeof(Block) - size - sizeof(Tag)));
    free_block->info.isfree = 1;
    tagekle(free_block);

        free_block->next = b->next;
        if(b->next != NULL)
            b->next->prev = free_block;        
        
        free_block->prev = last_freed;
    
    if(b == free_list){
        free_list = free_block;
    }

    if(listtype == ADDR_ORDERED_LIST){

        Block *current_free = free_list;
        int flag = 0;
        while((char*)current_free < (char*)free_block){
            if(current_free->next == NULL){

                current_free->next = free_block;
                free_block->prev = current_free;
                free_block->next = NULL;
                flag = 1;
                break;
            }
            else{
                current_free = next_block_in_freelist(current_free);
            }
        }
        if(flag == 0 && free_block != free_list){
            if(current_free->prev != NULL){
                current_free->prev->next = free_block;
                free_block->prev = current_free->prev;
            }
            else
                free_block->prev = NULL;
            
            current_free->prev = free_block;
            free_block->next = current_free;
        }

    }
    else{
        Block *current_free = free_list;
        while(current_free->next != NULL){
            current_free = next_block_in_freelist(current_free);
        }
        free_block->prev = current_free;
        current_free->next = free_block;
        free_block->next = NULL;
    }

    // Eğer free listesi sona gelinmediyse yeni bloğu ekler
    if (b->next != NULL) {
        free_block->next = b->next;
        b->next->prev = free_block;
    }
    b->next = free_block;
    free_block->prev = b;

    // Oluşturulan bloğun bilgileri güncelleniyor
    b->info.size = nsize;
    b->info.isfree = 0;
    tagekle(b);

    // Eğer yeni oluşturulan blok free listesindeyse ve dolu listeye geçirilmeliyse
    if (listtype == ADDR_ORDERED_LIST && b == last_freed) {
        last_freed = free_block;
    }
    return b; 
}

/** coalesce b with its left neighbor
 * returns the final block
 */
Block *left_coalesce(Block *b) { 
        //sola birleştirilip soldaki block döndürülür
        Block *prev_block = prev_block_in_addr(b);
        if (prev_block != NULL && prev_block->info.isfree) {
            prev_block->info.size += numberof16blocks(((b->info.size*16) + sizeof(Tag) + sizeof(Block)));
            prev_block->next = b->next;
            if (b->next != NULL) {
                b->next->prev = prev_block;
            }
            return prev_block;
        }
        else
            return b;

}

/** coalesce b with its left neighbor
 * returns the final block
 */
Block *right_coalesce(Block *b) { 
        //sağa birleştirilip sağdaki blok döndürülür
        Block *next_block = next_block_in_addr(b);
        if (next_block != NULL && next_block->info.isfree) {
            b->info.size += numberof16blocks(((next_block->info.size*16) + sizeof(Tag) + sizeof(Block)));
            b->next = next_block->next;
            if (next_block->next != NULL) {
                next_block->next->prev = b;
            }
            next_block->info.size = 0;
            return b;
        }
        else
            return  b;
}

/** for a given block returns its next block in the list*/
Block *next_block_in_freelist(Block *b) { 
    return b->next; 
}

/** for a given block returns its prev block in the list*/
Block *prev_block_in_freelist(Block *b) { 
    return b->prev;
}

/** for a given block returns its right neghbor in the address*/
Block *next_block_in_addr(Block *b) { 

    if(b == heap_end){
        return NULL;
    }
    Block *next = (Block*)((char*)b + sizeof(Block) + ((b->info.size)*16) + sizeof(Tag));
    return next;
}

/** for a given block returns its left neghbor in the address*/
Block *prev_block_in_addr(Block *b) { 
    
    if(b == heap_start){
        return NULL;
    }
    Tag *prevTag = (Tag *)((char*)b - sizeof(Tag));
    int size = ((prevTag->size) * 16);
    Block *prev = (Block *)((char *)b - sizeof(Block) - size - sizeof(Tag));
    prev->info.size = prevTag->size;
    return prev;
}

/**for a given size in bytes, returns number of 16 blocks*/
uint64_t numberof16blocks(size_t size_inbytes) { 
    return (size_inbytes + 15) / 16;
}

/** prints meta data of the blocks
 * --------
 * size:
 * free:
 * --------
 */
void printheap() {
    Block *current = heap_start;  
    while(current != NULL && current < heap_end){
        printf("----------\nsize: %ld\nfree:%d\n",current->info.size,current->info.isfree);
        current = next_block_in_addr(current);
    }

}

ListType getlisttype() { 
    return listtype; 
}

int setlisttype(ListType llisttype) { 
    listtype = llisttype;
    return 0; 
}

Strategy getstrategy() { 
    return strategy; 
}

int setstrategy(Strategy sstrategy) {
    strategy = sstrategy; 
    return 0; 
}
